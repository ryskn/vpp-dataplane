/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Replay driver, shared by all four targets.
 *
 * This is the binary the blocking PR gate runs. It has no coverage feedback
 * and no randomness that is not seeded to a fixed value, so two runs of the
 * same tree produce the same work and the same result — which is the whole
 * point of the deterministic half of the #67 decision:
 *
 *   "security regression の主要な gate は deterministic corpus と sanitizer
 *    とする"
 *
 * Usage:
 *   fuzz_<target> [options] [path ...]
 *
 *     path                 a corpus file, or a directory replayed in sorted
 *                          order so that the report is stable
 *     --generate           run the deterministic generator matrix (PR level)
 *     --generate-full      run the nightly generator matrix
 *     --require-outcomes   fail when an outcome the target marks required was
 *                          never produced; a corpus that cannot reach a
 *                          branch is not testing it
 *     --quiet              summary only
 */

#include "cilium_fuzz.h"

#include <dirent.h>
#include <sys/stat.h>

static int opt_quiet;
static unsigned long n_files;

static int
name_cmp (const void *a, const void *b)
{
  return strcmp (*(const char *const *) a, *(const char *const *) b);
}

static void
replay_file (const char *path)
{
  uint8_t buf[CILIUM_FUZZ_MAX_INPUT];
  size_t n;
  FILE *f = fopen (path, "rb");

  if (f == NULL)
    {
      fprintf (stderr, "%s: cannot open corpus file %s\n", cilium_fuzz_target_name, path);
      exit (2);
    }

  n = fread (buf, 1, sizeof (buf), f);

  /* A corpus file larger than the framing bound would be silently truncated,
     and a truncated regression input does not reproduce the bug it was
     committed for. Refuse it instead. */
  if (!feof (f) && n == sizeof (buf))
    {
      fprintf (stderr, "%s: corpus file %s exceeds %d octets\n", cilium_fuzz_target_name, path,
	       CILIUM_FUZZ_MAX_INPUT);
      exit (2);
    }
  fclose (f);

  n_files++;
  cilium_fuzz_one (buf, n);
}

static void
replay_path (const char *path)
{
  struct stat st;
  DIR *d;
  struct dirent *e;
  char **names = NULL;
  size_t n_names = 0, cap = 0, i;

  if (stat (path, &st) != 0)
    {
      fprintf (stderr, "%s: cannot stat %s\n", cilium_fuzz_target_name, path);
      exit (2);
    }

  if (!S_ISDIR (st.st_mode))
    {
      replay_file (path);
      return;
    }

  d = opendir (path);
  if (d == NULL)
    {
      fprintf (stderr, "%s: cannot open directory %s\n", cilium_fuzz_target_name, path);
      exit (2);
    }

  while ((e = readdir (d)) != NULL)
    {
      char *p;
      size_t len;

      if (e->d_name[0] == '.')
	continue;
      /* MANIFEST.md and README.md document the corpus; they are not inputs. */
      len = strlen (e->d_name);
      if (len > 3 && strcmp (e->d_name + len - 3, ".md") == 0)
	continue;

      len = strlen (path) + 1 + len + 1;
      p = (char *) malloc (len);
      if (p == NULL)
	abort ();
      snprintf (p, len, "%s/%s", path, e->d_name);

      if (n_names == cap)
	{
	  cap = cap ? cap * 2 : 64;
	  names = (char **) realloc (names, cap * sizeof (*names));
	  if (names == NULL)
	    abort ();
	}
      names[n_names++] = p;
    }
  closedir (d);

  qsort (names, n_names, sizeof (*names), name_cmp);
  for (i = 0; i < n_names; i++)
    {
      replay_path (names[i]);
      free (names[i]);
    }
  free (names);
}

int
main (int argc, char **argv)
{
  int i, generate = 0, generate_full = 0, require = 0, n_paths = 0, rc = 0;
  unsigned o;

  for (i = 1; i < argc; i++)
    {
      if (strcmp (argv[i], "--generate") == 0)
	generate = 1;
      else if (strcmp (argv[i], "--generate-full") == 0)
	generate_full = 1;
      else if (strcmp (argv[i], "--require-outcomes") == 0)
	require = 1;
      else if (strcmp (argv[i], "--quiet") == 0)
	opt_quiet = 1;
      else if (argv[i][0] == '-')
	{
	  fprintf (stderr, "%s: unknown option %s\n", cilium_fuzz_target_name, argv[i]);
	  return 2;
	}
      else
	n_paths++;
    }

  if (!generate && !generate_full && n_paths == 0)
    {
      fprintf (stderr,
	       "usage: %s [--generate|--generate-full] [--require-outcomes] [--quiet] [path ...]\n",
	       cilium_fuzz_target_name);
      return 2;
    }

  for (i = 1; i < argc; i++)
    if (argv[i][0] != '-')
      replay_path (argv[i]);

  if (generate)
    cilium_fuzz_generate (0);
  if (generate_full)
    cilium_fuzz_generate (1);

  printf ("%s: %lu corpus files, %lu runs\n", cilium_fuzz_target_name, n_files,
	  cilium_fuzz_n_runs);

  if (!opt_quiet)
    for (o = 0; cilium_fuzz_outcome_name[o] != NULL; o++)
      printf ("  %-32s %lu\n", cilium_fuzz_outcome_name[o], cilium_fuzz_outcome_count[o]);

  if (require)
    {
      for (o = 0; cilium_fuzz_outcome_name[o] != NULL; o++)
	{
	  if (!cilium_fuzz_outcome_required[o])
	    continue;
	  if (cilium_fuzz_outcome_count[o] == 0)
	    {
	      fprintf (stderr, "%s: outcome %s was never produced; the corpus no longer reaches "
			       "that branch\n",
		       cilium_fuzz_target_name, cilium_fuzz_outcome_name[o]);
	      rc = 1;
	    }
	}
    }

  if (rc == 0)
    printf ("%s: all post-conditions hold\n", cilium_fuzz_target_name);
  return rc;
}
