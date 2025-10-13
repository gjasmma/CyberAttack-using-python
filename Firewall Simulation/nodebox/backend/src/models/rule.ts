export enum Action {
  ALLOW = "ALLOW",
  BLOCK = "BLOCK",
}

export interface Rule {
  name: string;
  regex: RegExp;
  action: Action;
}
