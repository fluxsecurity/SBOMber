import axios from "axios";
import { get as httpGet } from "axios";

export async function fetchOne(url) {
  await axios.post(url, {});
  return httpGet(url);
}
