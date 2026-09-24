import os
from dotenv import load_dotenv

load_dotenv()

print("dev-ol7m540dysftaa5e.us.auth0.com:", os.getenv("dev-ol7m540dysftaa5e.us.auth0.com"))
print("MHJDsruIjtFiPSA7WWNHPZcgYAJubpFN:", os.getenv("MHJDsruIjtFiPSA7WWNHPZcgYAJubpFN"))
print("PcOLP07K0fOlqykPCUa88rts2dwtJjVneyKCqzdhM1yJuUH2rBoQLb30DyS3F0Mq loaded:", bool(os.getenv("PcOLP07K0fOlqykPCUa88rts2dwtJjVneyKCqzdhM1yJuUH2rBoQLb30DyS3F0Mq")))
print("http://localhost:8000/callback:", os.getenv("http://localhost:8000/callback"))