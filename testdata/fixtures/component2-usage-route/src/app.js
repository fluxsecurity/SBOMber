import { template } from "lodash";

function renderWelcome(name) {
  return template("Welcome");
}

function sendWelcome(name) {
  return renderWelcome(name);
}

app.get("/welcome", (request, response) => {
  return response.send(sendWelcome(request.name));
});
