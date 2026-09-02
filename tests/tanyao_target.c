/* tanyao_target.c — controllable target process for write-gate & long-session tests.
 * Behavior: hp decays 1/0.5s and resets at 0; gold +7/0.5s; px +0.5f/0.5s;
 * score +0.001; nonce +1. p2 static. link[0]=p link[1]=p2 (pointer-chain material).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

typedef struct Stats {
    int64_t kills;
    int64_t deaths;
    double kda;
} Stats;

typedef struct Player {
    int32_t hp;
    int32_t mp;
    uint32_t gold;
    uint32_t gems;
    float px, py, pz;
    float yaw;
    double score;
    char name[32];
    uint64_t nonce;
    struct Player *party_member; /* p -> p2 */
    Stats *stats;                /* p -> stats : 3rd deref level */
} Player;

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    Player *p  = malloc(sizeof(Player));
    Player *p2 = malloc(sizeof(Player));
    Stats  *st = malloc(sizeof(Stats));
    memset(p, 0, sizeof(Player));
    memset(p2, 0, sizeof(Player));
    memset(st, 0, sizeof(Stats));
    p->hp = 100; p->mp = 50; p->gold = 1000; p->gems = 10;
    p->px = 100.0f; p->py = 200.0f; p->pz = 300.0f; p->yaw = 90.0f;
    p->score = 12345.678;
    strcpy(p->name, "Hero");
    p2->hp = 77; p2->gold = 222;
    p->nonce = 0xDEADBEEFCAFEBABEULL;
    p->party_member = p2;
    p->stats = st;
    st->kills = 100; st->deaths = 4; st->kda = 25.0;

    void **link = malloc(sizeof(void *) * 4);
    link[0] = p;
    link[1] = p2;
    link[2] = st;

    printf("TANYAO_TARGET_READY pid=%d p=%p p2=%p st=%p link=%p\n",
           getpid(), (void *)p, (void *)p2, (void *)st, (void *)link);

    int round = 0;
    while (1) {
        round++;
        p->hp -= 1;
        if (p->hp < 0) p->hp = 100;
        p->gold += 7;
        p->px += 0.5f;
        p->score += 0.001;
        p->nonce++;
        if (round % 10 == 0)
            printf("round=%d hp=%d gold=%u px=%.2f score=%.3f kills=%lld deaths=%lld\n",
                   round, p->hp, p->gold, p->px, p->score,
                   (long long)st->kills, (long long)st->deaths);
        usleep(500000);
    }
    return 0;
}
