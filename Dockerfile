# -------- BUILD STAGE --------
FROM maven:3.9.9-eclipse-temurin-21 AS build

WORKDIR /build

COPY . .

RUN mvn -B -pl gateway-service -am clean package -DskipTests

# -------- RUNTIME STAGE --------
FROM eclipse-temurin:21-jre

WORKDIR /app

# Copy jar from build stage
COPY --from=build /build/gateway-service/target/*.jar app.jar

# copy OpenTelemetry agent
COPY otel/opentelemetry-javaagent.jar /otel/opentelemetry-javaagent.jar

# Expose default Spring Boot port
EXPOSE 8084

# Run the application
#ENTRYPOINT ["java","-jar","app.jar"]
ENTRYPOINT ["java","-javaagent:/otel/opentelemetry-javaagent.jar","-jar","app.jar"]