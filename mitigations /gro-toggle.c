/* gro-toggle: minimal ethtool -K for GRO features (no ethtool on the box).
 * Disables netdev features by name via ETHTOOL_SFEATURES, prints gro state.
 *
 * Usage:
 *   gro-toggle <iface>                 # disable rx-gro-list, rx-udp-gro-forwarding, rx-gro
 *   gro-toggle <iface> -k              # just print gro-related feature state
 *   gro-toggle <iface> feat1 feat2 ... # disable named features
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <linux/if.h>

static int fd;
static char ifname[IFNAMSIZ];

static int ethtool_call(void *data)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_data = (void *)data;
	return ioctl(fd, SIOCETHTOOL, &ifr);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <iface> [-k | feat...]\n", argv[0]);
		return 2;
	}
	strncpy(ifname, argv[1], IFNAMSIZ - 1);

	int list_only = (argc == 3 && strcmp(argv[2], "-k") == 0);

	const char *deflist[] = {"rx-gro-list", "rx-udp-gro-forwarding", "rx-gro"};
	const char **targets;
	int n_targets;
	if (argc > 2 && !list_only) {
		targets = (const char **)&argv[2];
		n_targets = argc - 2;
	} else {
		targets = deflist;
		n_targets = 3;
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) { perror("socket"); return 1; }

	/* number of features */
	struct { struct ethtool_sset_info hdr; __u32 buf[1]; } sset;
	memset(&sset, 0, sizeof(sset));
	sset.hdr.cmd = ETHTOOL_GSSET_INFO;
	sset.hdr.sset_mask = 1ULL << ETH_SS_FEATURES;
	if (ethtool_call(&sset) < 0) { perror("GSSET_INFO"); return 1; }
	__u32 n = sset.hdr.sset_mask ? sset.buf[0] : 0;
	if (!n) { fprintf(stderr, "%s: no features\n", ifname); return 1; }

	/* feature name strings */
	struct ethtool_gstrings *strs =
		calloc(1, sizeof(*strs) + (size_t)n * ETH_GSTRING_LEN);
	strs->cmd = ETHTOOL_GSTRINGS;
	strs->string_set = ETH_SS_FEATURES;
	strs->len = n;
	if (ethtool_call(strs) < 0) { perror("GSTRINGS"); return 1; }

	int blocks = (n + 31) / 32;

	/* current values */
	struct ethtool_gfeatures *gf =
		calloc(1, sizeof(*gf) + (size_t)blocks * sizeof(struct ethtool_get_features_block));
	gf->cmd = ETHTOOL_GFEATURES;
	gf->size = blocks;
	if (ethtool_call(gf) < 0) { perror("GFEATURES"); return 1; }

#define ACTIVE(i) (!!(gf->features[(i)/32].active & (1u << ((i)%32))))

	if (list_only) {
		for (__u32 i = 0; i < n; i++) {
			const char *nm = (char *)&strs->data[i * ETH_GSTRING_LEN];
			if (strstr(nm, "gro"))
				printf("%s: %s = %s\n", ifname, nm, ACTIVE(i) ? "on" : "off");
		}
		return 0;
	}

	/* build set request: disable each target */
	struct ethtool_sfeatures *sf =
		calloc(1, sizeof(*sf) + (size_t)blocks * sizeof(struct ethtool_set_features_block));
	sf->cmd = ETHTOOL_SFEATURES;
	sf->size = blocks;

	int changed = 0;
	for (int t = 0; t < n_targets; t++) {
		int found = -1;
		for (__u32 i = 0; i < n; i++) {
			const char *nm = (char *)&strs->data[i * ETH_GSTRING_LEN];
			if (strcmp(nm, targets[t]) == 0) { found = (int)i; break; }
		}
		if (found < 0) {
			printf("%s: feature '%s' not found (skip)\n", ifname, targets[t]);
			continue;
		}
		sf->features[found/32].valid |= (1u << (found%32));
		/* requested bit 0 = disable */
		sf->features[found/32].requested &= ~(1u << (found%32));
		changed++;
		printf("%s: %s %s -> off\n", ifname, targets[t], ACTIVE(found) ? "on" : "off");
	}

	if (changed && ethtool_call(sf) < 0) {
		fprintf(stderr, "%s: SFEATURES failed: %s\n", ifname, strerror(errno));
		return 1;
	}

	/* re-read + print gro features */
	if (ethtool_call(gf) < 0) { perror("GFEATURES(post)"); return 1; }
	for (__u32 i = 0; i < n; i++) {
		const char *nm = (char *)&strs->data[i * ETH_GSTRING_LEN];
		if (strstr(nm, "gro"))
			printf("%s: [post] %s = %s\n", ifname, nm, ACTIVE(i) ? "on" : "off");
	}
	return 0;
}
