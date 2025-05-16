import { Router } from 'express';
// Node.js v18+ tiene fetch globalmente. Si usas una versión anterior, necesitarías un polyfill como 'node-fetch'.

const newsRouter = Router();

//Middleware to check if the user is authenticated
//This middleware will check if the user is authenticated and if not it will return a 401 error

const authValid = (req, res, next) => {
    console.log("Entro al middleware authValid")
    if (req.isAuthenticated()) { // req.isAuthenticated()método proporcionado por passport verifica si el usuario está autenticado.
      // Si el usuario está autenticado, continúa con la siguiente función
      console.log("Esta autenticado")
      return next();
    } else {
      // Si no está autenticado, manda un mensaje 
      console.log("No esta autenticado")
      return res.status(401).send({ msg: "Unauthorized User" }); 
    }
};

newsRouter.get('/top-headlines', authValid, async (req, res) => {
    try {
        const { country = 'us', page = 1, pageSize = 10 } = req.query; // Obtener parámetros del query
        const apiKey = process.env.NEWS_API_KEY;

        if (!apiKey) {
            return res.status(500).json({ message: 'API key for news service is not configured.' });
        }

        const newsApiUrl = `https://newsapi.org/v2/top-headlines?country=${country}&apiKey=${apiKey}&page=${page}&pageSize=${pageSize}`;

        const fetchResponse = await fetch(newsApiUrl);

        if (!fetchResponse.ok) {
            // Intentar obtener el cuerpo del error si NewsAPI lo proporciona
            let errorDetails = { message: `Error from NewsAPI: ${fetchResponse.status} ${fetchResponse.statusText}` };
            try {
                const errorData = await fetchResponse.json();
                errorDetails = errorData; // Usar el mensaje de error de NewsAPI si está disponible
            } catch (e) {
                // No hacer nada si el cuerpo del error no es JSON o está vacío
            }
            console.error('Error fetching news from NewsAPI:', fetchResponse.status, errorDetails);
            return res.status(fetchResponse.status).json({
                message: errorDetails.message || 'Error al obtener noticias desde el servicio externo.',
                code: errorDetails.code || 'externalServiceError'
            });
        }

        const data = await fetchResponse.json();
        res.json(data);

    } catch (error) {
        console.error('Network or other error fetching news:', error.message);
        res.status(500).json({ message: 'Error interno del servidor al intentar obtener noticias.', details: error.message });
    }
});

export default newsRouter;