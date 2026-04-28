const { createApp, fromNodeMiddleware, toNodeListener } = require('h3');
const { createServer } = require('http');

const app = createApp();
app.use(fromNodeMiddleware((req, res, next) => {
  try {
    res.status(401).json({ error: 'test' });
  } catch (err) {
    res.statusCode = 500;
    res.end(JSON.stringify({ error: err.message }));
  }
}));

const server = createServer(toNodeListener(app)).listen(3000, () => {
  fetch('http://localhost:3000')
    .then(r => r.json())
    .then(json => {
      console.log(json);
      server.close();
    });
});
