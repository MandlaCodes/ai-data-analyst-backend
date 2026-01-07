import os
from polar_sdk import Polar
from db import SessionLocal, get_user_by_email 

def create_metria_checkout(customer_email: str) -> str:
    """
    Generates a secure Polar checkout URL tied specifically to a registered user.
    """
    db = SessionLocal()
    try:
        # 1. Validation
        user = get_user_by_email(db, customer_email)
        if not user:
            print(f"Checkout block: {customer_email} attempted payment without account.")
            return None
            
        # 2. Polar Logic: Initialize client directly (No 'with' statement)
        polar = Polar(access_token=os.environ.get("POLAR_ACCESS_TOKEN"))
        
        # 3. Use the .custom.create method which is standard for single product checkouts
        # Note: product_id is a string, not a list.
        res = polar.checkouts.custom.create(
            product_id=os.environ.get("POLAR_PRODUCT_ID"),
            success_url=os.environ.get("POLAR_SUCCESS_URL"),
            customer_email=customer_email,
            # metadata allows us to track the user_id in the webhook later
            metadata={
                "user_id": str(user.id),
                "context": "neural_engine_activation"
            }
        )
        
        print(f"Checkout generated for User ID: {user.id}")
        return res.url

    except Exception as e:
        print(f"Critical error in Checkout Engine: {e}")
        return None
    finally:
        db.close()