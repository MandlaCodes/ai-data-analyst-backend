import os
from polar_sdk import Polar
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    """
    Final fix for Polar SDK v0.28.1.
    This version uses 'variant_id' instead of 'product_id'.
    """
    db = SessionLocal()
    try:
        # 1. Verify user exists
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"CHECKOUT ERROR: User {customer_email} not found.")
            return None
            
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        # Ensure this is the ID you provided earlier
        product_id = os.environ.get("POLAR_PRODUCT_ID") 

        if not token or not product_id:
            print("CHECKOUT ERROR: Missing Environment Variables.")
            return None

        # 2. Initialize Polar
        polar = Polar(access_token=token)
        
        # 3. Create checkout
        # In v0.28.1, the argument name is 'variant_id'
        res = polar.checkouts.create(
            variant_id=product_id,
            success_url="https://metria.dev/dashboard?payment=success",
            customer_email=customer_email,
            metadata={
                "user_id": str(user.id),
                "email": customer_email
            }
        )
        
        if res and hasattr(res, 'url'):
            print(f"CHECKOUT SUCCESS: {res.url}")
            return res.url
        
        return None

    except Exception as e:
        print(f"SDK ERROR DETAIL: {str(e)}")
        return None
    finally:
        db.close()