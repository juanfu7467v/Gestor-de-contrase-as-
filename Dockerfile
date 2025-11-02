# Usa la imagen oficial de Node.js como base (ligera y estable)
FROM node:20-slim

# Establece el puerto en una variable de entorno, que es una buena práctica
ENV PORT 3000

# Crea y establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos de configuración de dependencias primero
# Esto permite que Docker use el caché para la instalación de dependencias
COPY package*.json ./

# Instala las dependencias de producción
RUN npm install --only=production

# Copia todo el código fuente de la aplicación al contenedor
# Asegúrate de que tu .gitignore excluya el directorio 'node_modules' local.
COPY . .

# Expone el puerto que la aplicación escuchará (usa la variable ENV)
EXPOSE ${PORT}

# Comando para iniciar la aplicación (debe coincidir con el script 'start' de package.json)
CMD [ "npm", "start" ]
