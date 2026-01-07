import os
from polar_sdk import Polar
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    db = SessionLocal()
    try:
        # 1. Check DB
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"DATABASE ERROR: No user found for {customer_email}")
            return None
            
        # 2. Check Environment Variables
        token = os.environ.get("POLAR_ACCESS_TOKEN")
        product_id = os.environ.get("POLAR_PRODUCT_ID")

        if not token:
            print("CONFIG ERROR: POLAR_ACCESS_TOKEN is missing in Render Env Vars")
            return None
        if not product_id:
            print("CONFIG ERROR: POLAR_PRODUCT_ID is missing in Render Env Vars")
            return None

        # 3. Initialize and Call
        polar = Polar(access_token=token)
        
        # Using the flat syntax for v0.28.1
        res = polar.checkouts.custom.create(
            product_id=product_id,
            success_url="https://metria.dev/dashboard?payment=success",
            customer_email=customer_email,
            metadata={
                "user_id": str(user.id)
            }
        )
        
        if res and hasattr(res, 'url'):
            return res.url
        
        return None

    except Exception as e:
        # THIS WILL PRINT THE ACTUAL ERROR TO YOUR RENDER LOGS
        print(f"FULL SDK CRASH REPORT: {str(e)}")
        return None
    finally:
        db.close()