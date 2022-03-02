using Microsoft.EntityFrameworkCore;

namespace MessageServer
{
    public class ApplicationContext : DbContext
    {
        public DbSet<Datacell> Users { get; set; } = null!;
        public DbSet<Message> Messages { get; set; } = null!;
        public ApplicationContext(DbContextOptions<ApplicationContext> options)
            : base(options)
        {
            Database.EnsureCreated();   // создаем базу данных при первом обращении
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Datacell>();
        }
    }
}