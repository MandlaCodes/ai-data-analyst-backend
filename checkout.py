import os
from polar_sdk import Polar
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    """
    Generates a Polar Checkout URL for the 'Hire Your AI Analyst' flow.
    Updated for Polar SDK v1.1.0+ (using request object structure).
    """
    db = SessionLocal()
    try:
        # 1. Verify user exists in the production DB
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"CHECKOUT ERROR: User {customer_email} not found in DB.")
            return None
            
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        product_id = os.environ.get("POLAR_PRODUCT_ID")

        # 2. Safety check for Environment Variables
        if not token or not product_id:
            print("CHECKOUT ERROR: POLAR_ACCESS_TOKEN or POLAR_PRODUCT_ID missing in Render.")
            return None

        # 3. Initialize Polar Client
        polar = Polar(access_token=token)
        
        # 4. Create the checkout session
        # CRITICAL FIX: SDK v1.1.0+ expects a 'request' argument with the data
        res = polar.checkouts.custom.create(
            request={
                "products": [product_id],
                "success_url": "https://metria.dev/dashboard?payment=success",
                "customer_email": customer_email,
                "metadata": {
                    "user_id": str(user.id),
                    "email": customer_email
                }
            }
        )
        
        # Accessing the URL from the response object
        if res and hasattr(res, 'url'):
            print(f"CHECKOUT SUCCESS: URL generated for {customer_email}")
            return res.url
        
        print("CHECKOUT ERROR: Polar response did not contain a URL.")
        return None

    except Exception as e:
        # This catches the schema validation errors or API errors
        print(f"CRITICAL POLAR SDK ERROR: {str(e)}")
        return None
    finally:
        db.close()