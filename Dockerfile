
# Use the latest official Ubuntu image
FROM ubuntu:latest

# Install Python 3 and necessary dependencies
RUN apt-get update && apt-get install -y python3 python3-pip

# Copy the project files to the container
COPY . /app
WORKDIR /app

# Install required Python packages
RUN pip3 install pycryptodome

# Execute the Python script
CMD ["python3", "shikata_ga_nai.py"]
