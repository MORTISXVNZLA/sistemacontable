FROM node:22-slim
WORKDIR /app
COPY package.json server.js ./
COPY public ./public
ENV NODE_ENV=production DATA_DIR=/data PORT=3000
RUN mkdir -p /data && chown -R node:node /data /app
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s CMD node -e "fetch('http://localhost:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node","server.js"]
