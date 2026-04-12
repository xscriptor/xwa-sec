FROM node:20

WORKDIR /app

COPY package*.json ./

RUN npm install

# Copiamos el resto (aunque usemos volumen, esto asegura tener un base layer)
COPY . .

EXPOSE 4200

# Usamos npm start (que invocará ng serve hosteado universalmente)
CMD ["npm", "start"]
