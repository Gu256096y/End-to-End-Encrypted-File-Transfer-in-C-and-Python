#Guy Rav On

# Function to read the port from the port.info file
def read_port_from_file(filename):
    try:
        with open(filename, 'r') as file:
            port_str = file.readline().strip()
            if port_str.isdigit():
                port = int(port_str)
                if 1 <= port <= 65535:  # Validate port range
                    return port
            print("Invalid port in file, defaulting to 1256.")
    except FileNotFoundError:
        print(f"{filename} not found, defaulting to 1256.")

    return 1256  # Default port if file not found or invalid
