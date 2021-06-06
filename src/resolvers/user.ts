import { User } from "../entities/User";
import { MyContext } from "src/types";
import {
  Arg,
  Ctx,
  Field,
  InputType,
  Mutation,
  ObjectType,
  Resolver,
} from "type-graphql";
import argon2 from "argon2";

@InputType()
class UsernamePasswordInput {
  @Field()
  username: string;

  @Field()
  password: string;
}

@ObjectType()
class FieldError {
  @Field()
  field: string;

  @Field()
  message: string;
}

@ObjectType()
class UserResponse {
  @Field(() => [FieldError], { nullable: true })
  errors?: FieldError[];

  @Field(() => User, { nullable: true })
  user?: User;
}

@Resolver()
export class UserResolver {
  @Mutation(() => UserResponse)
  async register(
    @Arg("body", () => UsernamePasswordInput)
    { username, password }: UsernamePasswordInput,
    @Ctx() { em }: MyContext
  ): Promise<UserResponse> {
    if (username.length <= 2) {
      return {
        errors: [
          {
            field: "username",
            message: "Length must be greater than 2",
          },
        ],
      };
    }
    if (password.length <= 3) {
      return {
        errors: [
          {
            field: "password",
            message: "Length must be greater than 2",
          },
        ],
      };
    }
    const hashPassword = await argon2.hash(password);
    const user = em.create(User, { username, password: hashPassword });
    try {
      await em.persistAndFlush(user);
    } catch (err) {
      if (err.code === "23505") {
        // duplicate username
        return {
          errors: [
            {
              field: "username",
              message: "Username already taken",
            },
          ],
        };
      }
    }
    return { user };
  }

  @Mutation(() => UserResponse)
  async login(
    @Arg("body", () => UsernamePasswordInput)
    { username, password }: UsernamePasswordInput,
    @Ctx() { em }: MyContext
  ): Promise<UserResponse> {
    const user = await em.findOne(User, {
      username,
    });
    if (!user) {
      return {
        errors: [
          {
            field: "username",
            message: "That username doesn't exist",
          },
        ],
      };
    }
    if (await argon2.verify(user.password, password)) {
      return { user };
    }
    return {
      errors: [
        {
          field: "password",
          message: "Username or password does't match",
        },
      ],
    };
  }
}
