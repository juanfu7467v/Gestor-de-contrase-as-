# Usa la imagen oficial de Node.js como base
FROM node:20-slim

# Crea y establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos package.json y package-lock.json
# Esto permite que Docker use el caché para la instalación de dependencias
COPY package*.json ./

# Instala las dependencias de producción
RUN npm install --only=production

# Copia todo el código de la aplicación al contenedor
COPY . .

# Expone el puerto que la aplicación escuchará. Fly.io mapeará esto.
EXPOSE 3000

# Comando para iniciar la aplicación (debe coincidir con el script 'start' de package.json)
CMD [ "npm", "start" ]
