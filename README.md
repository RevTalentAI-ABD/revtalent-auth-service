# RevTalent Authentication & Identity Service

The **Authentication Service** is the security gatekeeper for the **RevTalent** microservices ecosystem. It handles user registration, credentials validation, JSON Web Token (JWT) issuance, email verification, and secure password reset operations.

---

##  How It Works (Security & Identity Flow)

The service acts as an JWT identity provider:

1. **User Onboarding / Registration**:
   - The client submits a sign-up request to the server.
   - The service creates a new user record with a hashed password (via BCrypt) and generates a verification OTP (One-Time Password).
   - A verification mail containing the OTP is dispatched asynchronously using the configured SMTP server.

2. **Account Activation / OTP Verification**:
   - The user inputs the received OTP .
   - Upon verification, the user account is marked as active and verified.

3. **Login & JWT Token Generation**:
   - The user authenticates him with their credentials.
   - Upon successful credentials match and status check (ensuring email is verified), the service issues a secure, signed JWT token.
   - The JWT contains user roles, subject claims, and expiration details, allowing downstream services to authorize incoming requests via the API Gateway.

---

##  Dependencies Added

The following packages are defined in the service's `pom.xml`:

- **Spring Boot Security** (`spring-boot-starter-security`): Configures authentication managers, filters, CORS, and password hashing algorithms (BCrypt).
- **Java JSON Web Token (JJWT)** (`jjwt-api`, `jjwt-impl`, `jjwt-jackson`): library used to create, sign, and parse JWT authorization tokens.
- **Spring Boot Mail** (`spring-boot-starter-mail`): Integrates SMTP services to send verification codes and account registration alerts.
- **Spring Boot Data JPA** (`spring-boot-starter-data-jpa`): ORM implementation using Hibernate to manage tables in MySQL.
- **MySQL Driver** (`mysql-connector-j`): Database connector runtime library.
- **Netflix Eureka Client** (`spring-cloud-starter-netflix-eureka-client`): Registers the Auth Service with the service registry.
- **Spring Cloud Config Client** (`spring-cloud-starter-config`): Pulls external database, SMTP, and system variables from the Config Server.
- **Lombok** (`lombok`): Auto-generates getters, setters, constructors, and builders to reduce boilerplate.
- **Jacoco Testing Quality Gate** (`jacoco-maven-plugin`): Enforces at least 80% code coverage.
