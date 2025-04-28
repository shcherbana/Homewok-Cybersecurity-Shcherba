import os
import base64
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from PIL import Image, PngImagePlugin

def generate_keys():
    """
    Generate a 4096-bit RSA key pair and save it to the 'keys' directory.
    """
    os.makedirs("keys", exist_ok=True)
    key = RSA.generate(4096)

    with open("keys/private.pem", 'wb') as private_file:
        private_file.write(key.export_key())

    with open("keys/public.pem", 'wb') as public_file:
        public_file.write(key.publickey().export_key())

    print("Key pair successfully generated and saved to the 'keys' directory.")

def sign_image(input_image_path, signed_image_path):
    """
    Sign an image using a private RSA key.
    The signature is encoded in base64 and split into two metadata fields
    for better hiding.
    
    Args:
        input_image_path (str): Path to the original image.
        signed_image_path (str): Path where the signed image will be saved.
    """
    image = Image.open(input_image_path)
    pixels = image.tobytes()
    file_hash = SHA256.new(pixels)

    with open("keys/private.pem", 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())

    signature = pkcs1_15.new(private_key).sign(file_hash)
    signature_encoded = base64.b64encode(signature).decode('utf-8')

    part1 = signature_encoded[:len(signature_encoded) // 2]
    part2 = signature_encoded[len(signature_encoded) // 2:]

    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("x-user-meta1", part1)
    metadata.add_text("x-user-meta2", part2)

    image.save(signed_image_path, "PNG", pnginfo=metadata)
    print(f"Image has been signed and saved as '{signed_image_path}'.")

def verify_signature(signed_image_path):
    """
    Verify the digital signature embedded in an image.

    Args:
        signed_image_path (str): Path to the signed image.
    """
    with open("keys/public.pem", 'rb') as pub_file:
        public_key = RSA.import_key(pub_file.read())

    signed_image = Image.open(signed_image_path)
    part1 = signed_image.info.get("x-user-meta1")
    part2 = signed_image.info.get("x-user-meta2")

    if not part1 or not part2:
        print("Signature not found or incomplete in the image.")
        return

    full_signature_encoded = part1 + part2
    extracted_signature = base64.b64decode(full_signature_encoded)

    pixels_signed = signed_image.tobytes()
    verify_hash = SHA256.new(pixels_signed)

    try:
        pkcs1_15.new(public_key).verify(verify_hash, extracted_signature)
        print("Signature verification successful. The image is authentic.")
    except (ValueError, TypeError):
        print("Signature verification failed. The image may have been altered.")

def main():
    """
    Main function that generates keys, signs an image, and verifies the signature.
    """
    input_image_path = "original.png"
    signed_image_path = "signed_image.png"

    generate_keys()
    sign_image(input_image_path, signed_image_path)
    verify_signature(signed_image_path)

if __name__ == "__main__":
    main()
