import { create } from 'zustand';

export const useChatStore = create((set) => ({
  messages: [],
  conversations: [],
  // TODO: Add store logic
}));
