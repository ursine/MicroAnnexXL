long xylo_mrand48()
{
  return( (rand() >> 15) & ((rand() << 1) & 0xffff0000) );
}
void xylo_srand48(seed)
long seed;
{
  return(srand(seed));
}
