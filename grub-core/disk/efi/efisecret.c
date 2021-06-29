#include <grub/err.h>
#include <grub/misc.h>
#include <grub/cryptodisk.h>
#include <grub/efi/efi.h>
#include <grub/efi/api.h>
#include <grub/dl.h>

GRUB_MOD_LICENSE ("GPLv3+");

static grub_efi_packed_guid_t secret_guid = GRUB_EFI_SECRET_TABLE_GUID;
static grub_efi_packed_guid_t tableheader_guid = GRUB_EFI_SECRET_TABLE_HEADER_GUID;
static grub_efi_packed_guid_t diskpasswd_guid = GRUB_EFI_DISKPASSWD_GUID;

/*
 * EFI places the secret in the lower 4GB, so it uses a UINT32
 * for the pointer which we have to transform to the correct type
 */
struct efi_secret {
  grub_uint64_t base;
  grub_uint64_t size;
};

struct secret_header {
  grub_efi_packed_guid_t guid;
  grub_uint32_t len;
};

struct secret_entry {
  grub_efi_packed_guid_t guid;
  grub_uint32_t len;
  char data[0];
};

static grub_err_t
grub_efi_secret_put (const char *arg __attribute__((unused)), int have_it,
                    char **ptr)
{
  struct secret_entry *e = (struct secret_entry *)(*ptr - (long)&((struct secret_entry *)0)->data);

  /* destroy the secret */
  grub_memset (e, 0, e->len);
  *ptr = NULL;

  if (have_it)
    return GRUB_ERR_NONE;

  return  grub_error (GRUB_ERR_ACCESS_DENIED, "EFI secret failed to unlock any volumes");
}

static grub_err_t
grub_efi_secret_find (struct efi_secret *s, char **secret_ptr)
{
  int len;
  struct secret_header *h;
  struct secret_entry *e;
  unsigned char *ptr = (unsigned char *)(unsigned long)s->base;

  /* the area must be big enough for a guid and a u32 length */
  if (s->size < sizeof (*h))
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "EFI secret area is too small");

  h = (struct secret_header *)ptr;
  if (grub_memcmp(&h->guid, &tableheader_guid, sizeof (h->guid)))
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "EFI secret area does not start with correct guid\n");
  if (h->len < sizeof (*h))
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "EFI secret area is too small\n");

  len = h->len - sizeof (*h);
  ptr += sizeof (*h);

  while (len >= (int)sizeof (*e)) {
    e = (struct secret_entry *)ptr;
    if (e->len < sizeof(*e) || e->len > (unsigned int)len)
      return grub_error (GRUB_ERR_BAD_ARGUMENT, "EFI secret area is corrupt\n");

    if (! grub_memcmp (&e->guid, &diskpasswd_guid, sizeof (e->guid))) {
      int end = e->len - sizeof(*e);

      /*
       * the passphrase must be a zero terminated string because the
       * password routines call grub_strlen () to find its size
       */
      if (e->data[end - 1] != '\0')
       return grub_error (GRUB_ERR_BAD_ARGUMENT, "EFI secret area disk encryption password is not zero terminated\n");

      *secret_ptr = e->data;
      return GRUB_ERR_NONE;
    }
    ptr += e->len;
    len -= e->len;
  }
  return grub_error (GRUB_ERR_BAD_ARGUMENT, "EFI secret aread does not contain disk decryption password\n");
}

static grub_err_t
grub_efi_secret_get (const char *arg __attribute__((unused)), char **ptr)
{
  unsigned int i;

  for (i = 0; i < grub_efi_system_table->num_table_entries; i++)
    {
      grub_efi_packed_guid_t *guid =
       &grub_efi_system_table->configuration_table[i].vendor_guid;

      if (! grub_memcmp (guid, &secret_guid, sizeof (grub_efi_packed_guid_t))) {
       struct efi_secret *s =
         grub_efi_system_table->configuration_table[i].vendor_table;

       return grub_efi_secret_find(s, ptr);
      }
    }
  return grub_error (GRUB_ERR_BAD_ARGUMENT, "No secret found in the EFI configuration table");
}

static struct grub_secret_entry secret = {
  .name = "efisecret",
  .get = grub_efi_secret_get,
  .put = grub_efi_secret_put,
};

GRUB_MOD_INIT(efisecret)
{
  grub_cryptodisk_add_secret_provider (&secret);
}

GRUB_MOD_FINI(efisecret)
{
  grub_cryptodisk_remove_secret_provider (&secret);
}
