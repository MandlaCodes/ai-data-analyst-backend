import os
from polar_sdk import Polar
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    """
    Generates a Polar Checkout URL.
    Syntax adjusted for Polar SDK v0.28.1.
    """
    db = SessionLocal()
    try:
        # 1. Verify user exists
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"CHECKOUT ERROR: User {customer_email} not found.")
            return None
            
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        product_id = os.environ.get("POLAR_PRODUCT_ID")

        if not token or not product_id:
            print("CHECKOUT ERROR: Environment variables missing.")
            return None

        # 2. Initialize Client
        polar = Polar(access_token=token)
        
        # 3. Create checkout using v0.x syntax
        # In this version, product_id is a direct keyword argument
        res = polar.checkouts.custom.create(
            product_id=product_id,
            success_url="https://metria.dev/dashboard?payment=success",
            customer_email=customer_email,
            metadata={
                "user_id": str(user.id),
                "email": customer_email
            }
        )
        
        # 4. Return the URL
        if res and hasattr(res, 'url'):
            print(f"CHECKOUT SUCCESS: {res.url}")
            return res.url
            
        return None

    except Exception as e:
        print(f"CRITICAL POLAR SDK ERROR: {str(e)}")
        return None
    finally:
        db.close()