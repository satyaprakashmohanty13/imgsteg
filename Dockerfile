# Use the official Python base image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application file
COPY app.py .

# Expose the port Streamlit runs on
EXPOSE 7860

# Command to run the Streamlit application
CMD ["streamlit", "run", "app.py"]