import defaultThing, { remote as remoteAlias } from "example-lib";
import * as tools from "example-lib";
import { localValue as localAlias } from "./local.js";
import feature from "./feature.js";
tools.run(defaultThing, remoteAlias, localAlias, feature);
export const handler = (request) => tools.handle(request);
export { localValue } from "./local.js";
export { default as publicFeature } from "./feature.js";
