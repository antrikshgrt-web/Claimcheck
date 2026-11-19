FROM eclipse-temurin:21-jdk
WORKDIR /app
COPY ClaimCheck.java index.html rules.json ./
CMD ["java", "ClaimCheck.java"]
