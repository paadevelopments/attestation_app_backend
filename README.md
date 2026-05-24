# Attestation Server

A Java-based backend service designed to verify Android device attestations. This project uses Jakarta Servlet API for handling requests and Bouncy Castle for cryptographic verification.

## Prerequisites

- **Java 17** or higher
- **Maven 3.6** or higher

## Getting Started

### Clone the Repository

To get a local copy of the source code, clone the repository using Git:

```bash
git clone https://github.com/paadevelopments/attestation_app_backend.git
cd attestation_app/backend
```

### Install Dependencies

Maven will automatically handle the installation of dependencies like Bouncy Castle and Jackson. Run the following command to build the project and download all necessary libraries:

```bash
mvn clean install
```

## Running the Application

### Option 1: Using Jetty (Recommended for Development)

The project is configured with the `jetty-maven-plugin`, allowing you to run the server quickly without a manual Tomcat installation.

1. Run the following command:
   ```bash
   mvn jetty:run
   ```
2. The server will start on [http://localhost:8080](http://localhost:8080).
3. The attestation endpoint will be available at `http://localhost:8080/attestation` (or as configured in your servlet mapping).

### Option 2: Using Apache Tomcat

1. Build the WAR file:
   ```bash
   mvn clean package
   ```
2. Find the generated `attestation.war` file in the `target/` directory.
3. Copy `attestation.war` to the `webapps` folder of your Tomcat installation.
4. Start Tomcat. The application will be accessible at `http://localhost:8080/attestation/`.

## Project Structure

- `src/main/java`: Contains the core logic for the Attestation Engine and Servlets.
- `src/main/resources`: Contains configuration files and trusted root certificates.
- `pom.xml`: Maven configuration file defining dependencies and build plugins.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
