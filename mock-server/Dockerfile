FROM openjdk:11-jre

WORKDIR /opt
#COPY src/assembly/java.security $JAVA_HOME/conf/security
COPY target/server.mock-*-bc/bcprov-jdk15on*.jar $JAVA_HOME/lib/ext/bcprov-jdk15on.jar
COPY target/server.mock*.jar ./server.mock.jar

CMD ["java", "-jar", "./server.mock.jar"]