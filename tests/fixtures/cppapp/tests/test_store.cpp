#include <gtest/gtest.h>
#include "../server/note_store.h"

TEST(NoteStore, SearchReturnsJson) {
  notes::NoteStore store(":memory:");
  EXPECT_EQ(store.search("x"), "[]");
}
