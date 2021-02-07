import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.86.0/testing/asserts.ts";
import { Algorithm, Keygrip } from "./mod.ts";
const { test } = Deno;

const keygrip = new Keygrip(["secret", "key", "right?"]);

test("sign w default key", () => {
  const hash = keygrip.sign("hello");
  assertEquals(hash, "iKqz7ejTrflNJquQ07r9SiCDBww7zOnAFO4EpEOEfAs");
});
test("sign w defined key", () => {
  const hash = keygrip.sign("a_message", "key");
  assertEquals(hash, "AP7s7f076uQ3RUJp4dS4IWBmEU-LsXc-xSHIQjXNjGg");
});
test("sign w key index", () => {
  const hash = keygrip.sign("testing", 2);
  assertEquals(hash, "eIVBQQXh-pdnSoSEyHgFuu0NQf0mqjI_fVCdovhfiyQ");
});
test("sign w custom key", () => {
  const hash = keygrip.sign("some_message", "hey");
  assertEquals(hash, "7RZEp6fjBg4Wk9Iu9XrVbAUSMwDEpBKluS6ubwC0SjA");
});
test("sign with sha512", () => {
  const keygrip = new Keygrip(["secret"], Algorithm.SHA512);
  const hash = keygrip.sign("sha512");
  assertEquals(
    hash,
    "EqUYUvV0LCMO5I58bOckQsPjOku2QVYhiACM5BWWb2DhpprSo-Nm_fhISVYCQA4MYEllco6ufclUhX79vvvmgQ",
  );
});

test("verify with default key", () => {
  assert(
    keygrip.verify(
      "hello_friend",
      "h_MovQO9FBaDFU82O3uUTKEGFrmXJ5-O6yWlhgxx4F4",
    ),
  );
});
test("verify with last key", () => {
  assert(
    keygrip.verify("oh_my_car", "6CsFQH0sdrFdv-CGRaTfQhpQ9REupcdUY-3h_1u1bNg"),
  );
});
test("verify with invalid key", () => {
  assert(
    !keygrip.verify(
      "secret_message__",
      "XrMKWn-6e47XmFJA8vr473lcdmBaB2SEbSiN1qgAS90",
    ),
  );
});

test("index with default key", () => {
  const idx = keygrip.index(
    "hello world",
    "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo",
  );
  assertEquals(idx, 0);
});
test("index with second key", () => {
  const idx = keygrip.index(
    "Deno is cool",
    "A1Rla2oemijlT_3bkYoXoB8p9KEhU5IDYTGNgBTDPjY",
  );
  assertEquals(idx, 1);
});
test("index with invalid key", () => {
  const idx = keygrip.index(
    "invalid message",
    "pQSUybBccTpA9JNc9eJEuvvX4O7pEgJyaAMBGzCAMRc",
  );
  assertEquals(idx, -1);
});
