import boto3
import json
from django.conf import settings
from botocore.exceptions import ClientError

class ECSWorkspaceManager:
    """Manages user workspaces using AWS ECS Fargate"""
    
    def __init__(self):
        self.ecs_client = boto3.client('ecs', region_name=settings.AWS_REGION)
        self.ec2_client = boto3.client('ec2', region_name=settings.AWS_REGION)
        self.elbv2_client = boto3.client('elbv2', region_name=settings.AWS_REGION)
        
        self.cluster_name = settings.ECS_CLUSTER_NAME
        self.task_definition = settings.CODE_SERVER_TASK_DEFINITION
        self.target_group_arn = settings.WORKSPACE_TARGET_GROUP_ARN
        self.security_group = settings.WORKSPACE_SECURITY_GROUP
        self.subnets = settings.WORKSPACE_SUBNETS
        
    def create_workspace(self, user):
        """
        Launch a new Fargate task for user's workspace
        """
        container_name = f"workspace-{user.id}"
        
        # Check if task already exists
        existing_task = self.get_user_task(user.id)
        if existing_task:
            return {
                'status': 'existing',
                'url': f"https://workspace-{user.id}.{settings.DOMAIN}",
                'task_arn': existing_task
            }
        
        try:
            # Run new Fargate task
            response = self.ecs_client.run_task(
                cluster=self.cluster_name,
                taskDefinition=self.task_definition,
                launchType='FARGATE',
                networkConfiguration={
                    'awsvpcConfiguration': {
                        'subnets': self.subnets,
                        'securityGroups': [self.security_group],
                        'assignPublicIp': 'ENABLED'  # Needed for internet access
                    }
                },
                overrides={
                    'containerOverrides': [{
                        'name': 'code-server',
                        'environment': [
                            {'name': 'PASSWORD', 'value': self._generate_password(user)},
                            {'name': 'USER_ID', 'value': str(user.id)},
                            {'name': 'USER_EMAIL', 'value': user.email}
                        ]
                    }]
                },
                tags=[
                    {'key': 'user_id', 'value': str(user.id)},
                    {'key': 'user_email', 'value': user.email},
                    {'key': 'workspace', 'value': 'code-server'}
                ],
                enableECSManagedTags=True,
                propagateTags='TASK_DEFINITION'
            )
            
            task_arn = response['tasks'][0]['taskArn']
            
            # Wait for task to be running and get its IP
            task_ip = self._wait_for_task_ip(task_arn)
            
            # Register task with ALB target group
            self._register_target(task_ip, user.id)
            
            return {
                'status': 'created',
                'url': f"https://workspace-{user.id}.{settings.DOMAIN}",
                'task_arn': task_arn,
                'ip': task_ip
            }
            
        except ClientError as e:
            raise Exception(f"Failed to create workspace: {str(e)}")
    
    def stop_workspace(self, user):
        """Stop user's workspace task"""
        task_arn = self.get_user_task(user.id)
        if not task_arn:
            return {'status': 'not_found'}
        
        # Deregister from ALB first
        task_ip = self._get_task_ip(task_arn)
        if task_ip:
            self._deregister_target(task_ip)
        
        # Stop the task
        self.ecs_client.stop_task(
            cluster=self.cluster_name,
            task=task_arn,
            reason=f'User {user.id} stopped workspace'
        )
        
        return {'status': 'stopped'}
    
    def get_user_task(self, user_id):
        """Find running task for a specific user"""
        try:
            response = self.ecs_client.list_tasks(
                cluster=self.cluster_name,
                desiredStatus='RUNNING'
            )
            
            if not response['taskArns']:
                return None
            
            # Get task details
            tasks = self.ecs_client.describe_tasks(
                cluster=self.cluster_name,
                tasks=response['taskArns']
            )
            
            # Find task with matching user_id tag
            for task in tasks['tasks']:
                for tag in task.get('tags', []):
                    if tag['key'] == 'user_id' and tag['value'] == str(user_id):
                        return task['taskArn']
            
            return None
            
        except ClientError:
            return None
    
    def _wait_for_task_ip(self, task_arn, max_attempts=30):
        """Wait for task to get an IP address"""
        import time
        
        for _ in range(max_attempts):
            ip = self._get_task_ip(task_arn)
            if ip:
                return ip
            time.sleep(2)
        
        raise Exception("Task failed to get IP address")
    
    def _get_task_ip(self, task_arn):
        """Get private IP of a task"""
        try:
            response = self.ecs_client.describe_tasks(
                cluster=self.cluster_name,
                tasks=[task_arn]
            )
            
            task = response['tasks'][0]
            
            # Get ENI (network interface) ID
            for attachment in task['attachments']:
                if attachment['type'] == 'ElasticNetworkInterface':
                    for detail in attachment['details']:
                        if detail['name'] == 'privateIPv4Address':
                            return detail['value']
            
            return None
            
        except (ClientError, IndexError, KeyError):
            return None
    
    def _register_target(self, ip_address, user_id):
        """Register task IP with ALB target group"""
        try:
            self.elbv2_client.register_targets(
                TargetGroupArn=self.target_group_arn,
                Targets=[{
                    'Id': ip_address,
                    'Port': 8080,
                    'AvailabilityZone': 'all'
                }]
            )
        except ClientError as e:
            print(f"Failed to register target: {e}")
    
    def _deregister_target(self, ip_address):
        """Deregister task IP from ALB target group"""
        try:
            self.elbv2_client.deregister_targets(
                TargetGroupArn=self.target_group_arn,
                Targets=[{'Id': ip_address}]
            )
        except ClientError as e:
            print(f"Failed to deregister target: {e}")
    
    def _generate_password(self, user):
        """Generate secure password for workspace"""
        import hashlib
        return hashlib.sha256(
            f"{user.id}_{user.email}_{settings.SECRET_KEY}".encode()
        ).hexdigest()[:16]
