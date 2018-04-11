# Time Based Identity Token (Tibit)

[![Maven Central](https://img.shields.io/maven-central/v/com.rfksystems/tibit.svg?style=flat-square)](http://mvnrepository.com/artifact/com.rfksystems/tibit)

API documentation is available [here](http://www.javadoc.io/doc/com.rfksystems/tibit/)

### The problem

Distributed systems often use various kinds of tokens for different purposes, often authentication and authorization.
Unfortunately, such tokens could potentially be hijacked in transit if the network is not secure enough, 
proper encryption is not used etc. Tibit is designed to, at least partially, mitigate this problem.

Imagine an OAuth flow as an example - Authorization server issues access token to Client that is then used
for subsequent requests against Authorization server. The problem with this approach is, similarly to
passwords, these tokens almost never change, and once issued, they often travel between the Client and 
Authorization server indefinitely.

Tibit helps mitigate this issue by introducing a time-dependent token that obscures the actual Access token
in a way that even if intercepted over the wire or otherwise, the token would be valid for only a very short period
of time, therefore if not preventing possibility of interception, makes it very difficult to make use of such
intercepted token.

### How does it work?

In principle, Tibit works similarly to HMAC that would have an embedded timestamp, where message 
is timestamp + the secret key itself.

Tibit is a message digest of timestamp and secret key pre-shared in a secure way by some authority
to what you could refer to Consumer.

Considering the example involving OAuth,
For any subsequent requests, Consumer would encode the secret key as Tibit token, and server then would verify
the validity of this token, given knowledge about the composition of this token (time + secret key).

This is how a Tibit token using SHA-256 digest looks like:

`!SHA-256:1523459931111:d90867d98da7ebd2f2f3c4766bae46f46c48457a17e7f842ad4f888699aa0bd7`

As you can see, the time is actually exposed as UNIX timestamp. Because message digests can not be decoded,
there must be some way to transmit the timestamp over the wire, hence, it is included as part of the token,
along with the digest algorithm used for the given digest.

Because the timestamp is included as part of the token, two things can now happen:

- The recipient server can create a hash from it's known secret key + timestamp and compare it to the received one.
- The digest essentially changes every second. 

Because of how the token comparison works, the recipient needs to only verify that a certain token was
issued at certain time by consumer with certain secret key. The token is also valid for only certain amount of time,
defined by the recipient server, but because the timestamp is also part of the digest, it can not be changed
without changing the message digest, which would make the token invalid.

### Requirements

Java 8+.

### Installation

Tibit is available in Maven Central.

#### Maven

```xml
<dependency>
    <groupId>com.rfksystems</groupId>
    <artifactId>tibit</artifactId>
    <version>VERSION</version>
</dependency>
```

#### Gradle

```groovy
compile group: 'com.rfksystems', name: 'tibit', version: 'VERSION'
```

### Usage

See [Api documentation](http://www.javadoc.io/doc/com.rfksystems/tibit/) or source of `com.rfksystems.tibit.Tibit`.
The class is very simple and only has a couple of public methods, so it should be very easy to understand.

## License

Apache License, Version 2.0
