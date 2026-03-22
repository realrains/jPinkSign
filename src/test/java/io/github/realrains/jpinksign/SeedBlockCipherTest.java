package io.github.realrains.jpinksign;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class SeedBlockCipherTest {
    @Test
    void testProcessBlockRequiresKey() {
        assertThrows(IllegalArgumentException.class, () -> PinkSignFunctions.processBlock(true, null, Fixtures.SEED_BLOCK_PLAIN));
    }

    @Test
    void testProcessBlockRequiresBlockSize() {
        assertThrows(IllegalArgumentException.class, () -> PinkSignFunctions.processBlock(true, Fixtures.SEED_BLOCK_KEY, new byte[] {0}));
    }

    @Test
    void testSetKeyRequiresFullBlock() {
        assertThrows(IllegalArgumentException.class, () -> PinkSignFunctions.setKey(new byte[15]));
    }
}
