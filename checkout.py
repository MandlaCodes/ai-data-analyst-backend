import os
from polar_sdk import Polar
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    """
    Final checkout logic for Metria. 
    Compatible with polar-sdk 0.28.1.
    """
    db = SessionLocal()
    try:
        # 1. Verify User
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"CHECKOUT ERROR: {customer_email} not in DB.")
            return None
            
        # 2. Env Vars
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        product_id = os.environ.get("POLAR_PRODUCT_ID")

        if not token or not product_id:
            print("CHECKOUT ERROR: Missing POLAR_ACCESS_TOKEN or POLAR_PRODUCT_ID.")
            return None

        # 3. Initialize Polar
        polar = Polar(access_token=token)
        
        # 4. Generate Checkout
        # v0.28.1 uses direct keyword arguments
        res = polar.checkouts.custom.create(
            product_id=product_id,
            success_url="https://metria.dev/dashboard?payment=success",
            customer_email=customer_email,
            metadata={
                "user_id": str(user.id),
                "email": customer_email
            }
        )
        
        if res and hasattr(res, 'url'):
            print(f"CHECKOUT SUCCESS: Generated URL for {customer_email}")
            return res.url
        
        return None

    except Exception as e:
        print(f"CRITICAL POLAR SDK ERROR: {str(e)}")
        return None
    finally:
        db.close()