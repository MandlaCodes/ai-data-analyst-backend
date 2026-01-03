import os
from polar_sdk import Polar
from dotenv import load_dotenv

# Load variables from your .env file
load_dotenv()

def create_metria_checkout():
    # 'with' ensures the Polar client is closed properly after use
    with Polar(access_token=os.environ.get("POLAR_ACCESS_TOKEN")) as polar:
        
        # This matches the code you found
        res = polar.checkouts.create(request={
            "products": [
                os.environ.get("POLAR_PRODUCT_ID") # Use your ID here
            ],
            "success_url": os.environ.get("POLAR_SUCCESS_URL"),
            "customer_email_fixed": True # Recommended for SaaS
        })
        
        # This 'res.url' is what you send to your user
        return res.url

# To test it manually:
if __name__ == "__main__":
    print(f"Test Checkout Link: {create_metria_checkout()}")