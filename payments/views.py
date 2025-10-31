import stripe
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from .models import Payment

stripe.api_key = settings.STRIPE_SECRET_KEY


@api_view(["POST"])
@permission_classes([AllowAny])
def create_payment(request):
    """
    Create a Stripe PaymentIntent and return its client_secret
    """
    try:
        amount = request.data.get("amount")  # in rupees (frontend)
        currency = request.data.get("currency", "usd")

        if not amount:
            return Response({"error": "Amount is required"}, status=400)

        # Stripe expects amount in the smallest currency unit (like paise or cents)
        amount_cents = int(float(amount) * 100)

        # Create a PaymentIntent
        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency=currency,
            # metadata={"user_id": request.user.id, "email": request.user.email},
            automatic_payment_methods={"enabled": True},
        )

        # Save to DB
        Payment.objects.create(
            user=request.user,
            stripe_payment_intent=intent.id,
            amount=amount,
            currency=currency,
            status=intent.status,
        )

        return Response(
            {
                "clientSecret": intent.client_secret,
                "publishableKey": settings.STRIPE_PUBLISHABLE_KEY,
            }
        )

    except Exception as e:
        return Response({"error": str(e)}, status=500)
