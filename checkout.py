import os
from polar_sdk import Polar
from dotenv import load_dotenv
from db import SessionLocal, get_user_by_email # Connect to your DB logic

load_dotenv()

def create_metria_checkout(customer_email: str) -> str:
    """
    Generates a secure Polar checkout URL tied specifically to a registered user.
    """
    # 1. Validation: Ensure the user exists in our DB before allowing payment
    db = SessionLocal()
    try:
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"Checkout block: {customer_email} attempted payment without account.")
            return None
            
        # 2. Polar Logic: Initialize client and generate link
        # Note: Using 'with' depends on the SDK version supporting context managers.
        # If your version throws an error, use: polar = Polar(access_token=...)
        with Polar(access_token=os.environ.get("POLAR_ACCESS_TOKEN")) as polar:
            
            checkout_request = {
                "products": [os.environ.get("POLAR_PRODUCT_ID")],
                "success_url": os.environ.get("POLAR_SUCCESS_URL"),
                "customer_email": customer_email, 
                "customer_email_fixed": True,      # Lockdown the email to prevent spoofing
                "metadata": {                      # Attach metadata for webhook tracking
                    "user_id": str(user.id),
                    "context": "neural_engine_activation"
                }
            }
            
            res = polar.checkouts.create(request=checkout_request)
            
            print(f"Checkout generated for User ID: {user.id}")
            return res.url

    except Exception as e:
        print(f"Critical error in Checkout Engine: {e}")
        return None
    finally:
        db.close()