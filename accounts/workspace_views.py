import docker
import socket
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

# Only connect to Docker if available (prevents crash on Render)
try:
    client = docker.from_env()
except Exception as e:
    client = None
    print(f"Docker not available: {e}")

def get_free_port():
    """Find an available port for user container."""
    s = socket.socket()
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_workspace(request):
    """Provision code-server container for the user"""
    
    # Check if Docker is available
    if client is None:
        return Response(
            {"error": "Workspace feature not available on this server"},
            status=status.HTTP_503_SERVICE_UNAVAILABLE
        )
    
    user = request.user
    container_name = f"workspace_{user.id}"
    try:
        # Check if container already exists
        container = client.containers.get(container_name)
        container.reload()
        if container.status == "running":
            return Response(
                {"url": f"http://workspace-{user.id}.apranova.com"},
                status=status.HTTP_200_OK,
            )
            # return Response(
            #     {"url": f"http://localhost:{container.attrs['HostConfig']['PortBindings']['8080/tcp'][0]['HostPort']}"},
            #     status=status.HTTP_200_OK,
            # )
        else:
            container.start()
            return Response(
                {"url": f"http://workspace-{user.id}.apranova.com"},
                status=status.HTTP_200_OK,
            )
            # return Response(
            #     {"url": f"http://localhost:{container.attrs['HostConfig']['PortBindings']['8080/tcp'][0]['HostPort']}"},
            #     status=status.HTTP_200_OK,
            # )
    except docker.errors.NotFound:
        port = get_free_port()
        user_volume = f"D:/ApraNova/Persistence/data/workspaces/{user.id}"  #Use Docker mounted volumes or your own Local Folder
        container = client.containers.run(
            "apra-nova-code-server:latest",
            name=container_name,
            detach=True,
            ports={"8080/tcp": port},
            environment={
                "PASSWORD": f"{user.id}_workspace",
                "VIRTUAL_HOST": f"workspace-{user.id}.apranova.com",
                "LETSENCRYPT_HOST": f"workspace-{user.id}.apranova.com",
                "LETSENCRYPT_EMAIL": f"{user.email}"  # Your email
            },
            volumes={user_volume: {"bind": "/home/coder/project", "mode": "rw"}},
            labels={"VIRTUAL_HOST": f"workspace-{user.id}.apranova.com"},
            network="proxy",  # Connect to the proxy network
            restart_policy={"Name": "unless-stopped"},
        )
        url = f"http://workspace-{user.id}.apranova.com"
        return Response(
            {"url": url, "msg": "Workspace created successfully."},
            status=status.HTTP_201_CREATED,
        )
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
