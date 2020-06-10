FROM node:12
COPY app.js /app.js
COPY *.json /
RUN npm install
ENTRYPOINT [ "node", "/app.js"]