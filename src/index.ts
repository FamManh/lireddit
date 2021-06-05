import { MikroORM } from "@mikro-orm/core";
import { __prod__ } from "./constants";
import microConfig from "./mikro-orm.config";
import express from "express";
import { ApolloServer } from "apollo-server-express";
import { buildSchema } from "type-graphql";
import { HelloResolver } from "./resolvers/hello";
const main = async () => {
  const orm = await MikroORM.init(microConfig);
  await orm.getMigrator().up();

  const app = express();

  app.get("/", (_, res) => {
    res.send("Hello");
  });

  const apolloServer = new ApolloServer({
    schema: await buildSchema({
      resolvers: [HelloResolver],
      validate: false
    }),
  });

  apolloServer.applyMiddleware({app})

  app.listen(4000, () => {
    console.log("Server started on localhost:4000");
  });
};

main().catch((error) => {
  console.log(error);
});