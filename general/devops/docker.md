# Docker

[toc]

## Basics & Setup

Docker is software that allows any application to packaged such that it can run on any hardware. Docker also specifies the versions of any global runtime dependencies (i.e. Node.js) which is useful for potentially code-breaking updates.

**Dockerfile** - A blueprint for how to build a Docker Image. A project that uses docker will specify a docker file such that other developers can use the same setting to build an image.

**Image** - A template for running a docker container. The image defines how the process will run for the project it is related to.

**Container** - A run process which is an instance of the image.



### Installing

## Dockerfile

The `Dockerfile` is just a file with this name, that defines the blueprint for an image. Think of it as a list of instructions for Setup

### FROM

```dockerfile
FROM node:14
```



### WORKDIR



### COPY



### RUN



`.dockerignore`



### Expose



### CMD





## Using Docker (CLI)

**Interacting with running Containers**

```bash
docker ps #lists currently running containers
```



**Building An Image**



**Running Containers**





## DockerHub





## Useful Dockerfile Templates

