#pragma once

extern "C" {
#include <libfdt.h>
}

#include <cassert>

namespace Dtb {

/**
 * Cell provides data structures and methods to handle cell based properties
 *
 * Device trees contain properties described by cells. The properties are
 * - stored in big endian
 * - the number of cells is specified by other properties like
 *   \#address-cells, \#size-cells, \#interrupt-cells
 * - a property has at most 4 cells
 *
 * Cells might be translated from one domain into another. The
 * translation is done by comparing regions, calculating the offset
 * relative to a region in the current domain and applying this offset
 * to a region in another domain. Therefore cells need relational
 * operation, addition and subtraction.
 */

class Cell
{
public:
  enum
  {
    Max_size = 4 /**< Maximal number of allowed cells */
  };

  /**
   * Construct a default invalid cell
   *
   * An invalid cell is a tuple of {~0U, ~0U, ~0U, ~0U}.
   */
  Cell()
  {
    for (auto &v: _values)
      v = (uint32_t)~0UL;
  }

  /**
   * Construct a Cell object from a device tree property
   *
   * \param values Pointer to the property values
   * \param size Number of cells in the property; Must be smaller than
   *             Max_size.
   */
  Cell(fdt32_t const *values, size_t size)
  {
    assert(size <= Max_size);
    for (auto &v: _values)
      v = 0;

    for (unsigned i = 0, offs = Max_size - size; i < size; ++i)
      _values[offs + i] = fdt32_to_cpu(values[i]);
  }

  /**
   * Construct a Cell object from a 32bit value
   *
   * \param val Value the cell should be set to
   */
  Cell(uint32_t val)
  {
    for (auto &v: _values)
      v = 0;

    _values[Max_size - 1] = val;
  }

  uint32_t const &operator [] (size_t idx) const
  {
    assert(idx < Max_size);
    return _values[idx];
  }

  /**
   * Check whether a Cell object is valid
   *
   * The default constructor set the cell to {~0U, ~0U, ~0U, ~0U}. If
   * the cell object contains anything else it is considered to be
   * valid.
   *
   * \return bool true if the cell is different from {~0U, ~0U, ~0U, ~0U}
   */
  bool is_valid() const
  {
    for (auto x: _values)
      if (x != ~0U)
        return true;
    return false;
  }

  /**
   * Add two Cell objects
   *
   * We assume that cells are stored as 32 bit values in big endian
   * order and can be added by simply adding the invidual 32 bit
   * values and any overflow from a previous addition.
   *
   * We do not check whether there is an overflow when adding the
   * highest 32 bit values.
   */
  Cell operator + (Cell const &other) const
  {
    Cell result;
    uint32_t carry = 0;
    for (int i = Max_size - 1; i >= 0; --i)
      {
        uint64_t a = _values[i];
        uint64_t b = other._values[i];
        uint64_t res = a + b + carry;
        carry = (res >> 32) ? 1 : 0;
        result._values[i] = static_cast<uint32_t>(res);
      }
    // XXX no overflow check yet
    return result;
  }

  /**
   * Subtract a Cell object from another
   *
   * We assume that cells are stored as 32 bit values in big endian
   * order and the difference can be calculate by simply subtracting
   * the invidual 32 bit values and any overflow from a previous
   * subtraction.
   *
   * We do not check whether a is larger than b in (a - b), which
   * would lead to an overflow.
   */
  Cell operator - (Cell const &other) const
  {
    Cell result;
    uint32_t carry = 0;
    for (int i = Max_size - 1; i >= 0; --i)
      {
        uint64_t a = _values[i];
        uint64_t b = other._values[i];
        uint64_t res = a - b - carry;
        carry = (res >> 32) ? 1 : 0;
        result._values[i] = static_cast<uint32_t>(res);
      }
    // XXX no overflow check yet
    return result;
  }

  /**
   * Relational operator Cell A < Cell B
   */
  bool operator < (Cell const &other) const
  { return cmp(other) == -1; }

  /**
   * Relational operator Cell A <= Cell B
   */
  bool operator <= (Cell const &other) const
  { return cmp(other) != 1; }

  /**
   * Relational operator Cell A == Cell B
   */
  bool operator == (Cell const &other) const
  { return cmp(other) == 0; }

  /**
   * Relational operator Cell A != Cell B
   */
  bool operator != (Cell const &other) const
  { return cmp(other) != 0; }

  /**
   * Relational operator Cell A >= Cell B
   */
  bool operator >= (Cell const &other) const
  { return cmp(other) != -1; }

  /**
   * Relational operator Cell A > Cell B
   */
  bool operator > (Cell const &other) const
  { return cmp(other) == 1; }

  /**
   * Check whether the cell object contains a valid memory address
   *
   * We consider any 32bit or 64bit value a valid memory address. If
   * the cell contains anything other than 0 in the highest order
   * values, it must be something else and cannot be interpreted as a
   * memory address.
   *
   * \return bool true, if the cell contains a 32bit or 64bit value.
   */
  bool is_uint64() const
  { return !_values[0] && !_values[1]; }

  /**
   * Get the memory address of this cell
   *
   * Returns the value of the cell as 64bit value. It asserts, that
   * the cell actually contains something, that can be interpreted as
   * memory address.
   *
   * \return uint64_t the cell contents as 64bit value
   */
  uint64_t get_uint64() const
  {
    assert(is_uint64());
    return (static_cast<uint64_t>(_values[2]) << 32) + _values[3];
  }

private:
  /**
   * Compare two cell objects
   *
   * We assume that cells are stored as 32 bit values in big endian
   * order and that we can compare them starting at the highest order
   * value.
   *
   * \param Cell cell object to compare with
   * \retval -1 cell is smaller than other cell
   * \retval 0  cells are equal
   * \retval 1  cells is larger than other cell
   */
  int cmp(Cell const &other) const
  {
    unsigned i;
    for (i = 0; i < Max_size; ++i)
      {
        if (_values[i] < other._values[i])
          return -1;
        if (_values[i] > other._values[i])
          return 1;
      }
    return 0;
  }

  uint32_t _values[Max_size];
};

/**
 * Data and methods associated with a range property in a device tree
 *
 * Ranges in a device tree describe to translation of regions from one
 * domain to another.
 */
class Range
{
public:
  /**
   * Translate an address from one domain to another
   *
   * This function takes an address cell and a size cell and
   * translates the address from one domain to another if there is a
   * matching range.
   *
   * \param[inout]  address    Address cell that shall be translated
   * \param[in]     size Size  Size cell associated with the address
   */
  bool translate(Cell *address, Cell const &size)
  {
    assert(address);

    if (match(*address, size))
      {
        *address = (*address - _child) + _parent;
        return true;
      }
    return false;
  }

  Range(Cell const &child, Cell const &parent, Cell const &length)
  : _child{child}, _parent{parent}, _length{length} {};

private:
  // ranges: child, parent, length
  //         child.cells  == this->cells
  //         parent.cells == parent.cells
  Cell _child;
  Cell _parent;
  Cell _length;

  // [address, address + size] subset of [child, child + length] ?
  bool match(Cell const &address, Cell const &size) const
  {
    Cell address_max = address + size;
    Cell child_max = _child + _length;
    return (_child <= address) && (address_max <= child_max);
  }
};

/**
 * Data and methods associated with a reg property in a device tree
 */
struct Reg
{
  Cell address;
  Cell size;

  Reg(Cell const &address, Cell const &size) : address{address}, size{size} {};

  bool operator == (Reg const &other) const
  { return (address == other.address) && (size == other.size); }

  bool operator != (Reg const &other) const
  { return !operator == (other); }
};

} // namespace Dtb
