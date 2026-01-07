import os
from polar_sdk import Polar
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    db = SessionLocal()
    try:
        # 1. Check if user exists
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"ERROR: User {customer_email} not found in database.")
            return None
            
        # 2. Check Env Vars
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        product_id = os.environ.get("POLAR_PRODUCT_ID")

        if not token:
            print("ERROR: POLAR_ACCESS_TOKEN is missing in Render.")
            return None
        if not product_id:
            print("ERROR: POLAR_PRODUCT_ID is missing in Render.")
            return None

        # 3. Call Polar API
        polar = Polar(access_token=token)
        
        # v0.28.1 Syntax
        res = polar.checkouts.custom.create(
            product_id=product_id,
            success_url="https://metria.dev/dashboard?payment=success",
            customer_email=customer_email,
            metadata={"user_id": str(user.id)}
        )
        
        if res and hasattr(res, 'url'):
            print(f"SUCCESS: Link generated: {res.url}")
            return res.url
        
        print("ERROR: Polar API returned success but no URL.")
        return None

    except Exception as e:
        print(f"CRITICAL SDK ERROR: {str(e)}")
        return None
    finally:
        db.close()