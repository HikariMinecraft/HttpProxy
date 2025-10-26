import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import 'dotenv/config';
import path from 'path';
import { fileURLToPath } from 'url';
import { aesDecrypt, aesEncrypt } from "./aes.js";
import { Command } from 'commander';
const program = new Command();

program
  .option('-p, --port <number>', 'set port', '4577')
  .option('-h, --host <string>', 'set host', '127.0.0.1')
  .option('-l, --log <string>', 'set log', 'false')

program.parse(process.argv);

const options = program.opts();
console.log(options);


const fastify = Fastify({ logger: options.log === 'true' ? true : false });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

await fastify.register(fastifyStatic, {
  root: path.join(__dirname, 'views'),
});

fastify.get("/", async (request, reply) => {
    return reply.code(405).send({ error: "Method Not Allowed" });
});

fastify.post("/api", async (request, reply) => {
    try {
        const data = JSON.parse(aesDecrypt(request.body.data,process.env.SECRET,process.env.IV));

        const target = data.target;
        const method = data.method;
        let sdata = data.data;
        const headers = data.headers;

        if(sdata instanceof Object){
          sdata = JSON.stringify(sdata);
        }
        try{
            const res = await fetch(target, {
                method: method,
                body: sdata,
                headers: headers
            });

            return reply.code(200).send({ status: "success", data: {
                status: res.status,
                headers: res.headers,
                data: await res.text()
            }});
        }catch(err){
            console.log(err);
            return reply.code(500).send({ error: err.message });
        }
    } catch (err) {
        return reply.code(500).send({ error: 'internal error' });
    }
});

fastify.get("/generate", async (request, reply) => {
    return reply.code(200).sendFile("generate.html");
});


// Endpoint to generate encrypted data with provided key/iv/text
fastify.post('/api/aes/generate', async (request, reply) => {
  try {
    const { key, iv, text } = request.body || {};

    if (typeof key !== 'string' || typeof iv !== 'string' || typeof text !== 'string') {
      return reply.code(400).send({ error: 'key, iv and text must be strings' });
    }

    // Basic length validation for AES-256-CBC: key 32 bytes, iv 16 bytes (when using utf8 string input)
    if (Buffer.from(key).length !== 32) {
      return reply.code(400).send({ error: 'key must be 32 bytes (UTF-8 string length 32)' });
    }
    if (Buffer.from(iv).length !== 16) {
      return reply.code(400).send({ error: 'iv must be 16 bytes (UTF-8 string length 16)' });
    }

    const encrypted = aesEncrypt(text, key, iv);
    return reply.code(200).send({ encrypted });
  } catch (err) {
    request.log.error(err);
    return reply.code(500).send({ error: 'internal error' });
  }
});

try {
  const address = await fastify.listen({ port: options.port, host: options.host });
  console.log(`Server listening at ${address}`);
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}