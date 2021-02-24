# NodeJS Restful Api's

[toc]

One of the most popular types of [API](https://www.mulesoft.com/platform/api) is REST or, as they’re sometimes known, RESTful APIs. REST or RESTful APIs were designed to take advantage of existing protocols. While REST - or **Representational State Transfer** - can be used over nearly any protocol, when used for web APIs it typically takes advantage of HTTP. This means that developers have no need to install additional software or libraries when creating a REST API.

One of the key advantages of REST APIs is that they provide a great deal of flexibility. Data is not tied to resources or methods, so REST can handle multiple types of calls, return different data formats and even change structurally with the correct implementation of hypermedia. This flexibility allows developers to [build an API](https://www.mulesoft.com/lp/ebook/api/building-api-blueprint) that meets your needs while also meeting the needs of very diverse customers. 

There are 6 key constraints to think about when considering whether a RESTful API is the right [type of API](https://www.mulesoft.com/resources/api/types-of-apis) for your needs:

- Client-Server: This constraint operates on the concept that the client and the server should be separate from each other and allowed to evolve individually.
- Stateless: REST APIs are stateless, meaning that calls can be made independently of one another, and each call contains all of the data necessary to complete itself successfully.
- Cache: Because a stateless API can increase request overhead by handling large loads of incoming and outbound calls, a REST API should be designed to encourage the storage of cacheable data.
- Uniform Interface: The key to the decoupling client from server is having a uniform interface that allows independent evolution of the application without having the application’s services, or models and actions, tightly coupled to the API layer itself.
- Layered System: REST APIs have different layers of their architecture working together to build a hierarchy that helps create a more scalable and modular application.
- Code on Demand: Code on Demand allows for code or applets to be transmitted via the API for use within the application.



Node, the runtime environment for Javascript, has a few accessible frameworks and libraries for building a RESTful server. The main ones are Express & Koa, however node on its own can be used for this purpose too. Deno has Oak for this purpose, with others available.



## Core Concepts







## Node (bare)





## Express





## Koa





## Oak (deno)