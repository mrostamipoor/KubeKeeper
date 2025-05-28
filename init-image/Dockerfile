# Use the official Golang image from the Docker Hub
FROM golang:latest

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download
# Copy the source code into the container
COPY . .

# Build the application
RUN go build -v -o decrypt-secrets

# Command to run the executable
CMD ["/app/decrypt-secrets"]
