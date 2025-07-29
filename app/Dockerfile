# Use an official Node.js runtime as a parent image
FROM node:14

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install app dependencies
RUN npm install

# Copy app source code
COPY . .

# --- Requirement: Add wizexercise.txt with your name ---
# This command creates the file during the image build process.
RUN echo "Its Meghraj TO-DO LIST on Tuesday" > wizexercise.txt

# Make port 3000 available to the world outside this container
EXPOSE 3000

# Run app.js when the container launches
CMD ["node", "app.js"]
