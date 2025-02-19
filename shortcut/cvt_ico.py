from PIL import Image

def convert_to_ico(input_image, output_image):
    """
    Convert an image to ICO format.

    Args:
        input_image (str): Path to the input image (JPG or PNG).
        output_image (str): Path to the output image (ICO).
    """

    try:
        # Open the image
        img = Image.open(input_image)

        # Convert to ICO format
        img.save(output_image, format="ICO", sizes=[(32, 32)])

        print(f"Successfully converted {input_image} to {output_image}!")
    except Exception as e:
        print(f"Error during conversion: {e}")

if __name__ == "__main__":
    input_file = "key.png"  
    
    output_file = "key.ico"  
    
    convert_to_ico(input_file, output_file)
