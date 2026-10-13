# syntax=docker/dockerfile:1
ARG BASE=python:3.12-slim
FROM ${BASE} AS base
WORKDIR /app

FROM base AS builder
RUN echo build

FROM node:20-alpine@sha256:abcdef1234567890
COPY --from=builder /app /app
